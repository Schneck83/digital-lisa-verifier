import { NextRequest, NextResponse } from 'next/server';
import { Buffer } from 'buffer';
import * as bitcoin from 'bitcoinjs-lib';
import { createHash } from 'crypto';
import { Point, verify as nobleVerify, recoverPublicKey } from 'noble-secp256k1';

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

// Kompakte Signatur-Verifikation mit Recovery
async function verifySignature(
  pubKeyHex: string,
  signatureBase64: string,
  messageHash: Buffer
): Promise<boolean> {
  const sig = Buffer.from(signatureBase64, 'base64');
  const pubkeyCompressed = Uint8Array.from(Buffer.from(pubKeyHex, 'hex'));

  let pubkey: Uint8Array;
  try {
    // Entpacke den komprimierten Public Key (noble-secp256k1)
    pubkey = Point.fromHex(pubkeyCompressed).toRawBytes(false).slice(1);
  } catch (e) {
    console.error('Invalid pubkey format:', e);
    return false;
  }

  console.log('Signature length (bytes):', sig.length);
  console.log('Message hash:', messageHash.toString('hex'));

  if (sig.length === 65) {
    const recovery = (sig[0] - 27) % 4;
    if (recovery < 0 || recovery > 3) {
      console.log('Invalid recovery byte:', recovery);
      return false;
    }
    const compactSig = sig.slice(1);
    try {
const recoveredPubkeyCompressed = recoverPublicKey(messageHash, compactSig, recovery);      const recoveredPubkey = Point.fromHex(recoveredPubkeyCompressed).toRawBytes(false).slice(1);

      const derivedAddress = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(recoveredPubkey) }).address;
      console.log('Derived address from recovery:', derivedAddress);
      if (!derivedAddress) {
        console.log('Derived address is undefined');
        return false;
      }
      return await nobleVerify(compactSig, messageHash, pubkey);
    } catch (err) {
      console.log('Error during signature verification:', err);
      return false;
    }
  }

  console.log('Signature length not 65 bytes, verification failed');
  return false;
}

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);

    const uid = searchParams.get('uid');
    const lisaId = searchParams.get('lisa');
    const pubKey = searchParams.get('pub');
    const signature = searchParams.get('sig');

    if (!uid || !lisaId || !pubKey || !signature) {
      return NextResponse.json({ error: 'Missing parameters' }, { status: 400 });
    }

    // Nachricht zusammensetzen wie signiert
    const message = `uid=${uid}&lisa_id=${lisaId}`;

    console.log('Verifying NFC Signature with params:');
    console.log('Message:', message);
    console.log('Public Key:', pubKey);
    console.log('Signature (Base64):', signature);

    // Bitcoin Message Hash erzeugen
    const messageHash = bitcoinMessageHash(message);

    // Signatur prüfen
    const validSignature = await verifySignature(pubKey, signature, messageHash);

    console.log('Signature valid:', validSignature);

    // Dummy Meta-Daten für Beispiel (kannst du durch echtes Laden ersetzen)
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
    console.error('NFC verification error:', err);
    return NextResponse.json({
      error: 'Internal Server Error',
      message: err.message,
      stack: err.stack || null,
    }, { status: 500 });
  }
}