import { NextRequest, NextResponse } from 'next/server';
import { Buffer } from 'buffer';
import * as bitcoin from 'bitcoinjs-lib';
import { createHash } from 'crypto';
import * as tinySecp from 'tiny-secp256k1';

// Bitcoin-Message Hash nach BIP322
function bitcoinMessageHash(message: string): Buffer {
  const prefix = Buffer.from('\x18Bitcoin Signed Message:\n', 'utf8');
  const messageBuffer = Buffer.from(message, 'utf8');
  const lengthBuffer = Buffer.from([messageBuffer.length]);
  const buffer = Buffer.concat([prefix, lengthBuffer, messageBuffer]);
  const hash1 = createHash('sha256').update(buffer).digest();
  const hash2 = createHash('sha256').update(hash1).digest();
  return hash2;
}

async function verifySignature(
  pubKeyHex: string,
  signatureBase64: string,
  messageHash: Buffer
): Promise<boolean> {
  const sig = Buffer.from(signatureBase64, 'base64');
  const pubkeyCompressed = Buffer.from(pubKeyHex, 'hex');

  if (sig.length !== 65) {
    console.log('Ungültige Signaturlänge:', sig.length);
    return false;
  }

  const recovery = sig[0] - 27;
  if (recovery < 0 || recovery > 3) {
    console.log('Ungültiges Recovery-Byte:', recovery);
    return false;
  }

  const compactSig = sig.slice(1);

  try {
    // Public Key aus Signatur + Hash rekonstruieren
    const recoveredPubkey = tinySecp.recoverPublicKey(messageHash, compactSig, recovery);

    // Abgeleitete Adresse aus recovered Pubkey
    const derivedAddress = bitcoin.payments.p2wpkh({ pubkey: recoveredPubkey }).address;

    // Prüfe, ob recovered Address gleich der vom User angegebenen ist
    const originalAddress = bitcoin.payments.p2wpkh({ pubkey: pubkeyCompressed }).address;
    if (derivedAddress !== originalAddress) {
      console.log('Recovered address stimmt nicht überein');
      return false;
    }

    // Verifiziere Signatur (ohne Recovery Byte) gegen Public Key
    return tinySecp.verifySignature(compactSig, messageHash, pubkeyCompressed);
  } catch (e) {
    console.log('Fehler bei Verifikation:', e);
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

    // Bitcoin Message Hash erzeugen
    const messageHash = bitcoinMessageHash(message);

    // Signatur validieren
    const validSignature = await verifySignature(pubKey, signature, messageHash);

    console.log('Signatur gültig:', validSignature);

    // Dummy Meta-Daten (kannst du durch echte Daten ersetzen)
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