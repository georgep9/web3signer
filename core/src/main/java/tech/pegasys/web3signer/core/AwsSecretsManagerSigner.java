package tech.pegasys.web3signer.core;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.signers.secp256k1.EthPublicKeyUtils;
import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSSecretKey;
import tech.pegasys.web3signer.core.signing.ArtifactSignature;
import tech.pegasys.web3signer.core.signing.ArtifactSigner;
import tech.pegasys.web3signer.core.signing.BlsArtifactSignature;

import java.security.interfaces.ECPublicKey;

public class AwsSecretsManagerSigner implements ArtifactSigner {

  private AwsSecretsManagerKey awsSecretsManagerKey;
  private String publicKey;

  public AwsSecretsManagerSigner(byte[] publicKey){
    this.awsSecretsManagerKey = new AwsSecretsManagerKey(publicKey);
    this.publicKey = publicKey.toString();
  }

  @Override
  public String getIdentifier() {
    return this.publicKey;
  }

  @Override
  public ArtifactSignature sign(Bytes message) {
    BLSSecretKey blsSecretKey = BLSSecretKey.fromBytes(Bytes32.wrap(this.awsSecretsManagerKey.getPrivateKey()));
    return new BlsArtifactSignature(BLS.sign(blsSecretKey, message));
  }
}
