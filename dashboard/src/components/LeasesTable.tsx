import { useState } from 'react';
import {
  type ColumnDef,
  type SortingState,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table';
import type { LeaseView } from '../../../dist/dashboard/read.js';
import type { Capability } from '../../../dist/contract/index.js';

function capSummary(caps: Capability[]): string {
  if (!caps.length) return '—';
  return caps
    .map((c) => {
      switch (c.kind) {
        case 'fs.read':
          return `fs.read·${c.paths.length}`;
        case 'fs.write':
          return `fs.write·${c.paths.length}`;
        case 'http.call':
          return `http·${c.endpoints.length}`;
        case 'spend':
          return `spend ${(c.capMinor / 100).toFixed(2)} ${c.currency}`;
        default:
          return 'unknown';
      }
    })
    .join(', ');
}

const short = (id: string) => (id.length > 12 ? id.slice(0, 12) + '…' : id);
const fmtTime = (iso: string) => {
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
};

export function LeasesTable({
  leases,
  onRevoke,
}: {
  leases: LeaseView[];
  onRevoke: (leaseId: string) => void;
}) {
  const [sorting, setSorting] = useState<SortingState>([
    { id: 'status', desc: false },
  ]);

  const columns: ColumnDef<LeaseView>[] = [
    {
      id: 'status',
      accessorKey: 'status',
      header: 'Status',
      cell: (i) => {
        const s = i.getValue<string>();
        return <span className={`badge ${s}`}>{s}</span>;
      },
    },
    { id: 'id', accessorKey: 'id', header: 'Lease', cell: (i) => <span title={i.getValue<string>()}>{short(i.getValue<string>())}</span> },
    { id: 'agentId', accessorKey: 'agentId', header: 'Agent' },
    { id: 'taskId', accessorKey: 'taskId', header: 'Task' },
    {
      id: 'caps',
      header: 'Capabilities',
      accessorFn: (r) => capSummary(r.capabilities),
    },
    {
      id: 'expiresAt',
      accessorKey: 'expiresAt',
      header: 'Expires',
      cell: (i) => <span className="mono-dim">{fmtTime(i.getValue<string>())}</span>,
    },
    {
      id: 'spend',
      header: 'Spend',
      accessorFn: (r) =>
        r.capMinor !== undefined
          ? `${((r.spentMinor ?? 0) / 100).toFixed(2)} / ${(r.capMinor / 100).toFixed(2)}`
          : '—',
    },
    {
      id: 'action',
      header: '',
      enableSorting: false,
      cell: (i) => {
        const l = i.row.original;
        return (
          <button
            className="revoke"
            disabled={l.status !== 'active'}
            onClick={() => onRevoke(l.id)}
            title={l.status === 'active' ? 'Revoke this lease' : `Already ${l.status}`}
          >
            revoke
          </button>
        );
      },
    },
  ];

  const table = useReactTable({
    data: leases,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  return (
    <table>
      <thead>
        {table.getHeaderGroups().map((hg) => (
          <tr key={hg.id}>
            {hg.headers.map((h) => {
              const sorted = h.column.getIsSorted();
              return (
                <th
                  key={h.id}
                  onClick={h.column.getToggleSortingHandler()}
                  style={h.column.getCanSort() ? undefined : { cursor: 'default' }}
                >
                  {flexRender(h.column.columnDef.header, h.getContext())}
                  {sorted === 'asc' ? ' ▲' : sorted === 'desc' ? ' ▼' : ''}
                </th>
              );
            })}
          </tr>
        ))}
      </thead>
      <tbody>
        {table.getRowModel().rows.map((row) => (
          <tr key={row.id}>
            {row.getVisibleCells().map((cell) => (
              <td key={cell.id}>
                {flexRender(cell.column.columnDef.cell ?? ((c) => c.getValue()), cell.getContext())}
              </td>
            ))}
          </tr>
        ))}
        {leases.length === 0 && (
          <tr>
            <td colSpan={8} className="mono-dim" style={{ padding: '16px' }}>
              No leases — seed state with <code>npm run seed</code>.
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );
}
