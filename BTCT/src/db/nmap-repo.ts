import { db } from './database';
import type { NmapScan, NmapMachine, ID } from '@/types';
import { v4 as uuidv4 } from 'uuid';
import { getOrInitYText, setYTextValue, textKey } from '@/realtime/shared-doc';

export const nmapScanRepo = {
  /** Create an empty Nmap group (no XML yet). */
  async create(workspaceId: ID, name: string): Promise<NmapScan> {
    const scan: NmapScan = {
      id: uuidv4(),
      workspaceId,
      name,
      importedAt: Date.now(),
    };
    await db.nmapScans.add(scan);
    // Pre-seed the collaborative name Y.Text (invariant #1) so a later rename
    // has a Y.Text to update and the mirror never reverts it.
    getOrInitYText(textKey('nmapScan', scan.id, 'name'), scan.name);
    return scan;
  },

  /** Legacy: create group with raw XML attached. */
  async add(workspaceId: ID, name: string, rawXml: string): Promise<NmapScan> {
    const scan: NmapScan = {
      id: uuidv4(),
      workspaceId,
      name,
      importedAt: Date.now(),
      rawXml,
    };
    await db.nmapScans.add(scan);
    getOrInitYText(textKey('nmapScan', scan.id, 'name'), scan.name);
    return scan;
  },

  async getByWorkspace(workspaceId: ID): Promise<NmapScan[]> {
    return db.nmapScans.where('workspaceId').equals(workspaceId).reverse().sortBy('importedAt');
  },

  async rename(id: ID, name: string): Promise<void> {
    await db.nmapScans.update(id, { name });
    // `name` is a collaborative Y.Text: update it too or the mirror reverts
    // the record on the next sync/reload (invariant #2).
    setYTextValue('nmapScan', id, 'name', name);
  },

  async delete(id: ID): Promise<void> {
    await db.nmapMachines.where('scanId').equals(id).delete();
    await db.nmapScans.delete(id);
  },
};

export const nmapMachineRepo = {
  async addMany(machines: Omit<NmapMachine, 'id' | 'createdAt' | 'updatedAt'>[]): Promise<NmapMachine[]> {
    const now = Date.now();
    const records: NmapMachine[] = machines.map((m) => ({
      ...m,
      id: uuidv4(),
      createdAt: now,
      updatedAt: now,
    }));
    await db.nmapMachines.bulkAdd(records);
    for (const r of records) {
      getOrInitYText(textKey('nmapMachine', r.id, 'hostname'), r.hostname);
    }
    return records;
  },

  async getByScan(scanId: ID): Promise<NmapMachine[]> {
    return db.nmapMachines.where('scanId').equals(scanId).toArray();
  },

  async getAll(): Promise<NmapMachine[]> {
    return db.nmapMachines.toArray();
  },

  async update(id: ID, data: Partial<Pick<NmapMachine, 'hostname' | 'os'>>): Promise<void> {
    await db.nmapMachines.update(id, { ...data, updatedAt: Date.now() });
    // hostname is a collaborative Y.Text: keep it in sync when set here (the
    // inline editor uses useYTextInput, but a programmatic set must too).
    if (data.hostname !== undefined) setYTextValue('nmapMachine', id, 'hostname', data.hostname);
  },

  /** Upsert machines by IP within a group. Existing IPs get their ports/os/hostname updated. */
  async upsertByIp(groupId: ID, machines: Omit<NmapMachine, 'id' | 'createdAt' | 'updatedAt'>[]): Promise<void> {
    const existing = await db.nmapMachines.where('scanId').equals(groupId).toArray();
    const byIp = new Map(existing.map((m) => [m.ip, m]));
    const now = Date.now();
    const toAdd: NmapMachine[] = [];
    const toUpdate: { id: ID; data: Partial<NmapMachine> }[] = [];

    for (const m of machines) {
      const ex = byIp.get(m.ip);
      if (ex) {
        // Merge ports: keep existing ports, add/update from new scan
        const portMap = new Map(ex.ports.map((p) => [`${p.protocol}/${p.port}`, p]));
        for (const p of m.ports) {
          portMap.set(`${p.protocol}/${p.port}`, p);
        }
        toUpdate.push({
          id: ex.id,
          data: {
            ports: [...portMap.values()],
            hostname: m.hostname || ex.hostname,
            os: m.os !== 'unknown' ? m.os : ex.os,
            updatedAt: now,
          },
        });
      } else {
        toAdd.push({ ...m, id: uuidv4(), createdAt: now, updatedAt: now });
      }
    }

    if (toAdd.length > 0) {
      await db.nmapMachines.bulkAdd(toAdd);
      for (const r of toAdd) {
        getOrInitYText(textKey('nmapMachine', r.id, 'hostname'), r.hostname);
      }
    }
    for (const u of toUpdate) {
      await db.nmapMachines.update(u.id, u.data);
    }
  },

  async getById(id: ID): Promise<NmapMachine | undefined> {
    return db.nmapMachines.get(id);
  },

  async delete(id: ID): Promise<void> {
    await db.nmapMachines.delete(id);
  },

  async link(id: ID, nodeId: ID): Promise<void> {
    await db.nmapMachines.update(id, { linkedNodeId: nodeId, updatedAt: Date.now() });
  },

  async unlink(id: ID): Promise<void> {
    await db.nmapMachines.update(id, { linkedNodeId: undefined, updatedAt: Date.now() });
  },

  async getByLinkedNode(nodeId: ID): Promise<NmapMachine | undefined> {
    return db.nmapMachines.where('linkedNodeId').equals(nodeId).first();
  },

  async unlinkByNode(nodeId: ID): Promise<void> {
    const machines = await db.nmapMachines.where('linkedNodeId').equals(nodeId).toArray();
    for (const m of machines) {
      await db.nmapMachines.update(m.id, { linkedNodeId: undefined, updatedAt: Date.now() });
    }
  },
};
