import { createHash } from 'node:crypto';
import type { CertificateFileCleanupResult, CertificateFileCleanupTask } from '../domain/types.js';
import { Store } from '../store/store.js';

export class CertificateFileService {
  constructor(private readonly store: Store) {}

  private static keyFor(stockId: string, version: number): string {
    return `cert/${stockId}/v${version}`;
  }

  private static fingerprintOf(content: string): string {
    return createHash('sha256').update(content).digest('hex');
  }

  private tenantOf(stockId: string): string {
    return this.store.stocks.get(stockId)?.tenantId ?? 'system';
  }

  replace(stockId: string, version: number, content: string, fingerprint?: string): string {
    const tenantId = this.tenantOf(stockId);
    const oldKey = this.store.certificatePointers.get(stockId);
    const oldObject = oldKey ? this.store.certificateObjects.get(oldKey) : undefined;
    const newKey = CertificateFileService.keyFor(stockId, version);
    const newFingerprint = fingerprint ?? CertificateFileService.fingerprintOf(content);
    this.store.certificateObjects.set(newKey, { version, content, fingerprint: newFingerprint });
    this.store.certificatePointers.set(stockId, newKey);
    this.store.addAudit(tenantId, 'certificate-file.replaced', 'certificate', stockId, {
      version,
      objectKey: newKey,
      fingerprint: newFingerprint,
      replacedObjectKey: oldKey ?? '',
    });
    // Enqueue cleanup bound to the exact stale object: its version, key and fingerprint.
    // Never enqueue a task for the key just written (same-version re-upload).
    if (oldKey && oldKey !== newKey && oldObject) {
      const task: CertificateFileCleanupTask = { stockId, version: oldObject.version, objectKey: oldKey, fingerprint: oldObject.fingerprint };
      this.store.addOutbox(tenantId, 'mro.certificate-file-cleanup', stockId, task);
    }
    return oldKey ?? '';
  }

  cleanupOldVersion(task: CertificateFileCleanupTask): CertificateFileCleanupResult {
    const tenantId = this.tenantOf(task.stockId);
    const skip = (reason: string): CertificateFileCleanupResult => {
      this.store.addAudit(tenantId, 'certificate-file.cleanup-skipped', 'certificate', task.stockId, { objectKey: task.objectKey, version: task.version, reason });
      return reason === 'CURRENT_VERSION' ? 'SKIPPED_CURRENT' : 'SKIPPED_MISMATCH';
    };
    // The task must name the canonical key for the stock and version it claims to clean.
    if (task.objectKey !== CertificateFileService.keyFor(task.stockId, task.version)) return skip('KEY_VERSION_MISMATCH');
    // A late or out-of-order task must never delete the currently effective file.
    if (this.store.certificatePointers.get(task.stockId) === task.objectKey) return skip('CURRENT_VERSION');
    const target = this.store.certificateObjects.get(task.objectKey);
    // Duplicate delivery of an already-executed task: no-op, no duplicate audit.
    if (!target) return 'ALREADY_CLEANED';
    // The object at the key must be the exact object the task was created for;
    // a newer revision may have been written to the same key after the task was queued.
    if (target.version !== task.version || target.fingerprint !== task.fingerprint) return skip('FINGERPRINT_MISMATCH');
    this.store.certificateObjects.delete(task.objectKey);
    this.store.addAudit(tenantId, 'certificate-file.cleaned', 'certificate', task.stockId, { objectKey: task.objectKey, version: task.version, fingerprint: task.fingerprint });
    return 'CLEANED';
  }
}
