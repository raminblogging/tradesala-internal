/**
 * Feed Router
 * ────────────
 * GET    /feed/posts                          → paginated post list
 * POST   /feed/posts                          → create a post (text + optional image)
 * DELETE /feed/posts/:id                      → delete own post (admin can delete any)
 * POST   /feed/posts/:id/like                 → toggle like
 * GET    /feed/posts/:id/comments             → list comments
 * POST   /feed/posts/:id/comments             → add comment
 * GET    /feed/stats                          → feed activity summary
 */

import { json, verifyJWT, logActivity } from '../utils.js';

export async function FeedRouter(request, env, path) {
  const user = await verifyJWT(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401, request);

  const url = new URL(request.url);

  // ── GET /feed/posts ────────────────────────────────────────────
  if (path === '/feed/posts' && request.method === 'GET') {
    const offset = parseInt(url.searchParams.get('offset') || '0');
    const limit  = Math.min(parseInt(url.searchParams.get('limit')  || '10'), 30);

    const rows = await env.DB.prepare(`
      SELECT
        p.id,
        p.content,
        p.image_url,
        p.created_at,
        e.id         AS author_id,
        e.name       AS author_name,
        e.department,
        (SELECT COUNT(*) FROM post_likes    WHERE post_id = p.id)               AS likes_count,
        (SELECT COUNT(*) FROM post_comments WHERE post_id = p.id)               AS comments_count,
        (SELECT COUNT(*) FROM post_likes    WHERE post_id = p.id AND user_id = ?) AS user_liked
      FROM feed_posts p
      JOIN employees  e ON e.id = p.author_id
      ORDER BY p.created_at DESC
      LIMIT ? OFFSET ?
    `).bind(user.id, limit + 1, offset).all();

    const has_more = rows.results.length > limit;
    const posts    = rows.results.slice(0, limit).map(p => ({
      ...p,
      user_liked: p.user_liked > 0,
    }));

    return json({ posts, has_more }, 200, request);
  }

  // ── POST /feed/posts ───────────────────────────────────────────
  if (path === '/feed/posts' && request.method === 'POST') {
    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }

    const { content, image } = body;
    if (!content?.trim() && !image) {
      return json({ error: 'Post must contain text or an image' }, 400, request);
    }

    // Optional image upload to R2
    let image_url = null;
    if (image && env.R2_BUCKET) {
      try {
        const base64   = image.includes(',') ? image.split(',')[1] : image;
        const bytes    = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
        const key      = `feed/${Date.now()}-${user.id}.jpg`;
        await env.R2_BUCKET.put(key, bytes, {
          httpMetadata: { contentType: 'image/jpeg' },
        });
        image_url = `${env.R2_PUBLIC_URL}/${key}`;
      } catch (e) {
        console.warn('[R2 upload failed]', e?.message);
        // Continue — post without image rather than failing
      }
    }

    const now = new Date().toISOString();
    await env.DB.prepare(
      `INSERT INTO feed_posts (author_id, content, image_url, created_at)
       VALUES (?, ?, ?, ?)`
    ).bind(user.id, content?.trim() || '', image_url, now).run();

    await logActivity(env.DB, user.id, 'post', 'Shared a new post on the feed');

    return json({ ok: true }, 201, request);
  }

  // ── DELETE /feed/posts/:id ─────────────────────────────────────
  const postIdMatch = path.match(/^\/feed\/posts\/(\d+)$/);

  if (postIdMatch && request.method === 'DELETE') {
    const postId = postIdMatch[1];
    const post   = await env.DB.prepare(
      `SELECT id, author_id FROM feed_posts WHERE id = ?`
    ).bind(postId).first();

    if (!post) return json({ error: 'Post not found' }, 404, request);

    // Only the author or an admin can delete
    if (post.author_id !== user.id && user.role !== 'admin') {
      return json({ error: 'Forbidden' }, 403, request);
    }

    await env.DB.prepare(`DELETE FROM feed_posts WHERE id = ?`).bind(postId).run();
    return json({ ok: true }, 200, request);
  }

  // ── POST /feed/posts/:id/like ──────────────────────────────────
  const likeMatch = path.match(/^\/feed\/posts\/(\d+)\/like$/);

  if (likeMatch && request.method === 'POST') {
    const postId = likeMatch[1];
    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }

    if (body.liked) {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO post_likes (post_id, user_id, created_at) VALUES (?, ?, ?)`
      ).bind(postId, user.id, new Date().toISOString()).run();
    } else {
      await env.DB.prepare(
        `DELETE FROM post_likes WHERE post_id = ? AND user_id = ?`
      ).bind(postId, user.id).run();
    }
    return json({ ok: true }, 200, request);
  }

  // ── GET /feed/posts/:id/comments ───────────────────────────────
  const commentsMatch = path.match(/^\/feed\/posts\/(\d+)\/comments$/);

  if (commentsMatch && request.method === 'GET') {
    const rows = await env.DB.prepare(`
      SELECT c.id, c.content, c.created_at,
             e.name AS author_name,
             e.id   AS author_id
      FROM   post_comments c
      JOIN   employees      e ON e.id = c.author_id
      WHERE  c.post_id = ?
      ORDER  BY c.created_at ASC
    `).bind(commentsMatch[1]).all();

    return json({ comments: rows.results }, 200, request);
  }

  // ── POST /feed/posts/:id/comments ──────────────────────────────
  if (commentsMatch && request.method === 'POST') {
    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }

    const content = body.content?.trim();
    if (!content) return json({ error: 'Comment cannot be empty' }, 400, request);

    await env.DB.prepare(
      `INSERT INTO post_comments (post_id, author_id, content, created_at)
       VALUES (?, ?, ?, ?)`
    ).bind(commentsMatch[1], user.id, content, new Date().toISOString()).run();

    return json({ ok: true }, 201, request);
  }

  // ── GET /feed/stats ────────────────────────────────────────────
  if (path === '/feed/stats' && request.method === 'GET') {
    const today = new Date().toISOString().split('T')[0];

    const [todayCount, totalCount, activeCount] = await Promise.all([
      env.DB.prepare(
        `SELECT COUNT(*) as c FROM feed_posts WHERE date(created_at) = ?`
      ).bind(today).first(),
      env.DB.prepare(
        `SELECT COUNT(*) as c FROM feed_posts`
      ).first(),
      env.DB.prepare(
        `SELECT COUNT(DISTINCT author_id) as c FROM feed_posts
         WHERE  date(created_at) >= date('now', '-30 days')`
      ).first(),
    ]);

    return json({
      posts_today:    todayCount?.c  ?? 0,
      total_posts:    totalCount?.c  ?? 0,
      active_members: activeCount?.c ?? 0,
    }, 200, request);
  }

  return json({ error: 'Not found' }, 404, request);
}
