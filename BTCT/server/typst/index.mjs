// HTTP surface of the Typst server side. index.mjs imports this file
// dynamically, and only when ENABLE_TYPST is on.
import { capabilities, exportReport, ExportError, CLIENT_GONE } from './export.mjs';
import { encodeWarnings } from './warnings.mjs';

const MIME = { pdf: 'application/pdf', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' };

// The id names a room in the shared doc and, through stageReport, nothing on
// disk, but it still reaches a Y.Map lookup and an error message: keep it to
// the shape the client's ids actually have.
const WORKSPACE_ID = /^[A-Za-z0-9_-]{1,64}$/;

// Returns true when it handled the request.
export async function handleTypst(req, res, { user, sendJson, setCors = () => {} }) {
  const url = new URL(req.url, 'http://x');
  if (!url.pathname.startsWith('/api/typst/')) return false;
  // BTCT has no per-workspace ACL: every authenticated account can already
  // read every workspace through the shared doc, so a valid account token is
  // the whole authorization check, exactly as for /api/assets.
  if (!user) { sendJson(res, 401, { error: 'unauthorised' }); return true; }

  if (req.method === 'GET' && url.pathname === '/api/typst/capabilities') {
    // Asynchronous because the Word converter's answer is "can this Python
    // import pdf2docx", which is a child process. The result is cached, so
    // this is a promise that has usually already settled.
    sendJson(res, 200, await capabilities());
    return true;
  }

  const m = /^\/api\/typst\/([^/]+)\/export$/.exec(url.pathname);
  if (req.method === 'POST' && m) {
    const format = url.searchParams.get('format');
    if (format !== 'pdf' && format !== 'docx') { sendJson(res, 400, { error: 'format must be pdf or docx' }); return true; }
    let workspaceId;
    try { workspaceId = decodeURIComponent(m[1]); } catch { workspaceId = m[1]; }
    if (!WORKSPACE_ID.test(workspaceId)) { sendJson(res, 400, { error: 'invalid workspace id' }); return true; }
    // An export runs for as long as a compile takes, and a queued one can sit
    // behind another. If the caller gives up in the meantime there is no
    // point staging anything.
    // With no cap on the Word converter, a caller who gives up mid-export
    // must also stop the child, or it holds a core and the queue for nobody.
    // Bun 1.3 does not emit the response's 'close' when the client goes away
    // mid-request; it emits the request's 'aborted' and 'close' and the
    // socket's 'close' (measured with curl -m). Listening only to res 'close'
    // meant a disconnect was never seen, so every one of them is watched,
    // and a response that already finished is never treated as abandoned.
    let gone = false;
    const abandoned = new AbortController();
    const leave = () => {
      if (!gone && !res.writableFinished) {
        gone = true;
        abandoned.abort();
      }
    };
    req.on('aborted', leave);
    req.socket?.on('close', leave);
    res.on('close', leave);
    try {
      const { bytes, baked, warnings } = await exportReport(workspaceId, format, () => gone, abandoned.signal);
      const head = {
        'Content-Type': MIME[format],
        'Content-Length': bytes.byteLength,
        'X-Baked-Images': String(baked),
        'Cache-Control': 'no-store',
      };
      const encoded = encodeWarnings(warnings);
      if (encoded) head['X-Export-Warnings'] = encoded;
      // Binary responses do not go through sendJson, so CORS is set by hand.
      // Without the expose list a split-host browser can read neither header.
      setCors(res);
      if (res.getHeader('Access-Control-Allow-Origin')) {
        head['Access-Control-Expose-Headers'] = 'X-Baked-Images, X-Export-Warnings';
      }
      res.writeHead(200, head);
      res.end(bytes); // already a Buffer: copying it again would double a 100 MB file
    } catch (err) {
      // An ExportError's message is written for the operator. Anything else
      // may carry a staged path or a stack, so it is logged and never sent.
      if (err instanceof ExportError && err.status === CLIENT_GONE) { /* nobody to answer */ }
      else if (err instanceof ExportError) sendJson(res, err.status, { error: err.message, diagnostics: err.diagnostics ?? [] });
      else { console.error('[typst] export failed', err); sendJson(res, 500, { error: 'export failed' }); }
    }
    return true;
  }

  sendJson(res, 404, { error: 'not found' });
  return true;
}
