import { Suspense } from 'react';
import NFCPage from './verifier';

export default function NFCWrapperPage() {
  return (
    <Suspense fallback={<div className="p-6">⏳ Lade Lisa-Verifikation …</div>}>
      <NFCPage />
    </Suspense>
  );
}