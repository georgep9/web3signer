package tech.pegasys.web3signer.core;

import software.amazon.awssdk.services.kms.model.KeyMetadata;
import tech.pegasys.signers.secp256k1.api.Signature;
import tech.pegasys.signers.secp256k1.api.Signer;

import java.security.interfaces.ECPublicKey;

public class AwsKmsSigner implements Signer {

    private KeyMetadata keyMetadata;

    public AwsKmsSigner(KeyMetadata keyMetadata)


    @Override
    public Signature sign(byte[] data) {
        return null;
    }

    @Override
    public ECPublicKey getPublicKey() {
        return null;
    }
}
