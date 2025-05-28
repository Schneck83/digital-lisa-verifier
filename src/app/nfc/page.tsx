'use client';

import { useSearchParams } from 'next/navigation';
import { useEffect, useState } from 'react';

type VerificationResult = {
  validSignature: boolean;
  isCreatorPubKey: boolean;
  lisaId: string;
  anchorName: string;
  imagePreview: string;
  hqKeyRequestUrl: string;
};

export default function NFCPage() {
  const searchParams = useSearchParams();
  const lisa = searchParams.get('lisa');
  const pub = searchParams.get('pub');
  const sig = searchParams.get('sig');

  const [result, setResult] = useState<VerificationResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!lisa || !pub || !sig) {
      setError('Fehlende Parameter in der URL.');
      return;
    }

    const fetchVerification = async () => {
      try {
        const res = await fetch(`/api/verify?lisa=${lisa}&pub=${pub}&sig=${encodeURIComponent(sig)}`);
        const data = await res.json();
        setResult(data);
      } catch (err) {
        setError('Fehler bei der Verifikation.');
      }
    };

    fetchVerification();
  }, [lisa, pub, sig]);

  if (error) {
    return <div className="p-6 text-red-600">⚠️ {error}</div>;
  }

  if (!result) {
    return <div className="p-6">⏳ Verifiziere Lisa #{lisa} …</div>;
  }

  const { validSignature, isCreatorPubKey, anchorName, imagePreview, hqKeyRequestUrl } = result;
  const arImage = imagePreview.replace('ar://', 'https://arweave.net/');

  return (
    <div className="p-6 max-w-xl mx-auto text-center">
      <h1 className="text-2xl font-bold mb-4">🔎 Lisa #{lisa} Verifikation</h1>
      <img src={arImage} alt={anchorName} className="mx-auto mb-4 rounded-xl shadow-lg" />

      {validSignature && isCreatorPubKey ? (
        <div className="text-green-600 font-semibold mb-4">✅ Echtheit & Besitz bestätigt</div>
      ) : (
        <div className="text-red-600 font-semibold mb-4">❌ Signatur ungültig oder fremd</div>
      )}

      <p className="mb-4">🖼️ <strong>{anchorName}</strong></p>

      {validSignature && (
        <a
          href={hqKeyRequestUrl}
          className="inline-block bg-black text-white px-4 py-2 rounded hover:bg-gray-800 transition"
        >
          🔐 Zugriff auf HQ-Datei anfordern
        </a>
      )}
    </div>
  );
}