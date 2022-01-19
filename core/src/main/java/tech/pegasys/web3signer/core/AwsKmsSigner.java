package tech.pegasys.web3signer.core;

import org.apache.tuweni.bytes.Bytes;
import tech.pegasys.signers.secp256k1.EthPublicKeyUtils;
import tech.pegasys.signers.secp256k1.api.Signature;
import tech.pegasys.signers.secp256k1.api.Signer;
import tech.pegasys.web3signer.core.signing.SecpArtifactSignature;

import java.security.interfaces.ECPublicKey;

public class AwsKmsSigner implements Signer {

    private String keyId;
    private AwsKmsKey awsKmsKey;
    private ECPublicKey publicKey;

    public AwsKmsSigner(String keyId) {
        this.keyId = keyId;
        this.awsKmsKey = new AwsKmsKey(keyId);
        this.publicKey = EthPublicKeyUtils.createPublicKey(Bytes.wrap(this.awsKmsKey.publicKey()));
    }

    @Override
    public Signature sign(byte[] data) {
        byte[] signature = this.awsKmsKey.signData(data);
        return SecpArtifactSignature.fromBytes(Bytes.wrap(signature)).getSignatureData();
    }

    @Override
    public ECPublicKey getPublicKey() {
        return this.publicKey;
    }
}
