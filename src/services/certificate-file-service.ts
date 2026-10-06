import { createHash } from 'node:crypto';
import { Store } from '../store/store.js';

function fingerprintOf(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

function versionOfKey(objectKey: string): number | undefined {
  const match = /\/v(\d+)$/.exec(objectKey);
  const captured = match?.[1];
  return captured === undefined ? undefined : Number(captured);
}

export class CertificateFileService {
  constructor(private readonly store: Store) {}

  replace(stockId: string, version: number, content: string): string {
    const oldKey = this.store.certificatePointers.get(stockId);
    const newKey = `cert/${stockId}/v${version}`;
    this.store.certificateObjects.set(newKey, content);
    this.store.certificateObjectMeta.set(newKey, { stockId, version, fingerprint: fingerprintOf(content) });
    this.store.certificatePointers.set(stockId, newKey);
    if (oldKey && oldKey !== newKey) {
      const oldContent = this.store.certificateObjects.get(oldKey);
      if (oldContent !== undefined) {
        // Bind the cleanup task to the exact superseded object: its key, the
        // certificate version it belonged to and the fingerprint of its content.
        const oldMeta = this.store.certificateObjectMeta.get(oldKey);
        this.store.addOutbox('system', 'mro.certificate-file-cleanup', stockId, {
          stockId,
          version: oldMeta?.version ?? versionOfKey(oldKey) ?? version - 1,
          objectKey: oldKey,
          fingerprint: oldMeta?.fingerprint ?? fingerprintOf(oldContent),
        });
      }
    }
    return oldKey ?? '';
  }

  cleanupOldVersion(stockId: string, objectKey: string, version?: number, fingerprint?: string): void {
    // A late or out-of-order task must never delete the object the pointer
    // currently references: that is the effective certificate file.
    if (this.store.certificatePointers.get(stockId) === objectKey) {
      this.store.addAudit('system', 'certificate-file.cleanup-skipped', 'certificate', stockId, { objectKey, reason: 'object-is-current' });
      return;
    }
    const content = this.store.certificateObjects.get(objectKey);
    if (content === undefined) return; // already cleaned: duplicate tasks are a no-op
    const meta = this.store.certificateObjectMeta.get(objectKey);
    if (meta && meta.stockId !== stockId) {
      this.store.addAudit('system', 'certificate-file.cleanup-skipped', 'certificate', stockId, { objectKey, reason: 'stock-mismatch' });
      return;
    }
    const expectedFingerprint = meta?.fingerprint ?? fingerprintOf(content);
    if (fingerprint !== undefined && fingerprint !== expectedFingerprint) {
      this.store.addAudit('system', 'certificate-file.cleanup-skipped', 'certificate', stockId, { objectKey, reason: 'fingerprint-mismatch' });
      return;
    }
    if (version !== undefined && meta && version !== meta.version) {
      this.store.addAudit('system', 'certificate-file.cleanup-skipped', 'certificate', stockId, { objectKey, reason: 'version-mismatch' });
      return;
    }
    this.store.certificateObjects.delete(objectKey);
    this.store.certificateObjectMeta.delete(objectKey);
    const metadata: Record<string, string | number | boolean> = { objectKey, fingerprint: expectedFingerprint };
    const cleanedVersion = meta?.version ?? version;
    if (cleanedVersion !== undefined) metadata.version = cleanedVersion;
    this.store.addAudit('system', 'certificate-file.cleaned', 'certificate', stockId, metadata);
  }
}
