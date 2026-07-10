import {
  HeadContent,
  Outlet,
  Scripts,
  createRootRoute,
} from '@tanstack/react-router';

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title: 'leasebroker · governance console' },
    ],
  }),
  component: RootComponent,
});

function RootComponent() {
  return (
    <html lang="en">
      <head>
        <HeadContent />
        <style>{CSS}</style>
      </head>
      <body>
        <Outlet />
        <Scripts />
      </body>
    </html>
  );
}

const CSS = `
  :root {
    --bg: #0b0e12; --panel: #11151b; --panel-2: #161b22; --border: #232a33;
    --text: #c9d1d9; --dim: #6b7681; --accent: #d4a84b;
    --green: #3fb950; --red: #f85149; --grey: #6b7681; --orange: #db8b2a;
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text); font-family: var(--mono); font-size: 13px; }
  a { color: var(--accent); }
  .wrap { padding: 16px; max-width: 1500px; margin: 0 auto; }
  .topbar { display: flex; align-items: baseline; justify-content: space-between; border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 14px; }
  .title { font-size: 15px; font-weight: 700; letter-spacing: .04em; }
  .title small { color: var(--dim); font-weight: 400; margin-left: 8px; }
  .statedir { color: var(--dim); font-weight: 400; font-size: 11px; margin-top: 3px; max-width: 60vw; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .counts { display: flex; gap: 14px; align-items: center; }
  .count b { font-size: 16px; }
  .count.active b { color: var(--green); } .count.expired b { color: var(--grey); }
  .count.revoked b { color: var(--red); } .count.denials b { color: var(--orange); }
  .badge { display: inline-block; padding: 1px 7px; border-radius: 10px; font-size: 11px; text-transform: uppercase; letter-spacing: .03em; border: 1px solid; }
  .badge.active { color: var(--green); border-color: var(--green); }
  .badge.expired { color: var(--grey); border-color: var(--grey); }
  .badge.revoked { color: var(--red); border-color: var(--red); }
  .badge.intact { color: var(--green); border-color: var(--green); }
  .badge.tampered { color: var(--red); border-color: var(--red); }
  .grid { display: grid; grid-template-columns: minmax(0,1.6fr) minmax(360px,1fr); gap: 14px; align-items: start; }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  .panel h2 { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--dim); margin: 0; padding: 10px 12px; border-bottom: 1px solid var(--border); background: var(--panel-2); }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  th { color: var(--dim); font-size: 11px; text-transform: uppercase; cursor: pointer; user-select: none; }
  th:hover { color: var(--text); }
  tbody tr:nth-child(even) { background: var(--panel-2); }
  .mono-dim { color: var(--dim); }
  button.revoke { background: transparent; border: 1px solid var(--red); color: var(--red); border-radius: 5px; padding: 2px 8px; cursor: pointer; font: inherit; font-size: 11px; }
  button.revoke:hover { background: var(--red); color: #fff; }
  button.revoke:disabled { opacity: .3; cursor: default; }
  .feed { max-height: 78vh; overflow: auto; }
  .ev { display: grid; grid-template-columns: 88px 90px 1fr; gap: 8px; padding: 5px 12px; border-bottom: 1px solid var(--border); font-size: 12px; align-items: baseline; }
  .ev .t { color: var(--dim); white-space: nowrap; }
  .ev .ty { text-transform: uppercase; font-size: 10px; letter-spacing: .04em; }
  .ev .ty.denial, .ev .ty.revocation { color: var(--red); }
  .ev .ty.issuance { color: var(--green); }
  .ev .ty.decision, .ev .ty.request, .ev .ty.use { color: var(--dim); }
  .ev .d { color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .pending-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 8px 12px; border-bottom: 1px solid var(--border); }
  .pending-row .who { font-size: 12px; }
  .pending-row .scope { color: var(--dim); font-size: 11px; }
  .pending-actions { display: flex; gap: 6px; }
  button.approve { background: transparent; border: 1px solid var(--green); color: var(--green); border-radius: 5px; padding: 2px 8px; cursor: pointer; font: inherit; font-size: 11px; }
  button.approve:hover { background: var(--green); color: #fff; }
  .loading { padding: 40px; color: var(--dim); text-align: center; }
  .empty { padding: 14px; color: var(--dim); font-size: 12px; }
`;
