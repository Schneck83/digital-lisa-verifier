import { NextRequest, NextResponse } from 'next/server';
import { Buffer } from 'buffer';
import * as bitcoin from 'bitcoinjs-lib';
import { createHash } from 'crypto';
import { Point, verify as nobleVerify, recoverPublicKey } from 'noble-secp256k1';

// Erzeugt den Bitcoin-Message Hash (BIP322 Standard)
function bitcoinMessageHash(message: string): Buffer {
  const prefix = Buffer.from('\x18Bitcoin Signed Message:\n', 'utf8');
  const messageBuffer = Buffer.from(message, 'utf8');
  const lengthBuffer = Buffer.from([messageBuffer.length]);
  const buffer = Buffer.concat([prefix, lengthBuffer, messageBuffer]);
  const hash1 = createHash('sha256').update(buffer).digest();
  const hash2 = createHash('sha256').update(hash1).digest();
  return hash2;
}

// Prüft kompakte Signaturen (65 Bytes) inkl. Recovery-Byte
// Rekonstruiert Public Key aus Signatur+Hash und vergleicht mit gegebenem PubKey
async function verifySignature(
  pubKeyHex: string,
  signatureBase64: string,
  messageHash: Buffer
): Promise<boolean> {
  const sig = Buffer.from(signatureBase64, 'base64');
  if (sig.length !== 65) {
    console.log('Ungültige Signatur-Länge:', sig.length);
    return false;
  }

  const recovery = (sig[0] - 27) % 4;
  if (recovery < 0 || recovery > 3) {
    console.log('Ungültiges Recovery-Byte:', recovery);
    return false;
  }

  const compactSig = sig.slice(1); // 64 Bytes kompakte Signatur

  try {
    // Komprimierten Public Key aus Base16 (Hex) zu Uint8Array
    const pubkeyCompressed = Uint8Array.from(Buffer.from(pubKeyHex, 'hex'));
    // Entpacke zu 64-Byte unkomprimiert (ohne Prefix)
    const pubkey = Point.fromHex(pubkeyCompressed).toRawBytes(false).slice(1);

    // Rekonstruiere Public Key aus Signatur+Hash
    const recoveredPubkeyCompressed = recoverPublicKey(messageHash, compactSig, recovery);
    if (!recoveredPubkeyCompressed) {
      console.log('Fehler: Konnte Public Key nicht rekonstruieren');
      return false;
    }
    const recoveredPubkey = Point.fromHex(recoveredPubkeyCompressed).toRawBytes(false).slice(1);

    // Vergleiche den rekonstruierten Public Key mit dem übergebenen
    if (!Buffer.from(pubkey).equals(Buffer.from(recoveredPubkey))) {
      console.log('Rekonstruierter Public Key stimmt nicht mit übergebenem überein');
      return false;
    }

    // Verifiziere die Signatur (ohne Recovery Byte) gegen den Public Key
    const result = await nobleVerify(compactSig, messageHash, pubkey);
    return result;
  } catch (e) {
    console.log('Fehler bei Signatur-Verifikation:', e);
    return false;
  }
}

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);

    const uid = searchParams.get('uid');
    const lisaId = searchParams.get('lisa');
    const pubKey = searchParams.get('pub');
    const signature = searchParams.get('sig');

    if (!uid || !lisaId || !pubKey || !signature) {
      return NextResponse.json({ error: 'Fehlende Parameter' }, { status: 400 });
    }

    // Nachricht wie beim Signieren zusammensetzen
    const message = `uid=${uid}&lisa_id=${lisaId}`;

    console.log('Verifiziere NFC Signatur mit Parametern:');
    console.log('Message:', message);
    console.log('Public Key:', pubKey);
    console.log('Signature (Base64):', signature);

    // Erzeuge Bitcoin-Message Hash (BIP322)
    const messageHash = bitcoinMessageHash(message);

    // Signatur validieren
    const validSignature = await verifySignature(pubKey, signature, messageHash);

    console.log('Signatur gültig:', validSignature);

    // Beispiel-Metadaten (kannst du durch echte Daten ersetzen)
    const anchorName = `Digital Lisa #${lisaId}`;
    const imagePreview = `ar://OOqqylcAolOZbrnoEMmKmCyP9J3ZXiwkU6sCkT-dRU4`;
    const hqKeyRequestUrl = `https://verify.digital-lisa-club.xyz/request-key?lisa_id=${lisaId}`;

    return NextResponse.json({
      uid,
      lisaId,
      pubKey,
      signature,
      validSignature,
      anchorName,
      imagePreview,
      hqKeyRequestUrl,
    });
  } catch (err: any) {
    console.error('Fehler bei NFC Verifikation:', err);
    return NextResponse.json({
      error: 'Interner Serverfehler',
      message: err.message,
      stack: err.stack || null,
    }, { status: 500 });
  }
}