import { Store } from '../store/store.js';

export class CertificateFileService {
  constructor(private readonly store: Store) {}

  replace(stockId: string, version: number, content: string): string {
    const oldKey = this.store.certificatePointers.get(stockId);
    const newKey = `cert/${stockId}/v${version}`;
    this.store.certificateObjects.set(newKey, content);
    this.store.certificatePointers.set(stockId, newKey);
    if (oldKey) this.store.addOutbox('system', 'mro.certificate-file-cleanup', stockId, { stockId, version: version - 1, objectKey: oldKey });
    return oldKey ?? '';
  }

  cleanupOldVersion(stockId: string, objectKey: string): void {
    // BUG: the worker resolves the object by stockId at execution time instead of using the queued key.
    const currentKey = this.store.certificatePointers.get(stockId);
    if (currentKey) this.store.certificateObjects.delete(currentKey);
    this.store.addAudit('system', 'certificate-file.cleaned', 'certificate', stockId, { objectKey });
  }
}
