package tech.pegasys.web3signer.core;

import io.vertx.core.net.impl.KeyStoreHelper;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import tech.pegasys.signers.bls.keystore.KeyStore;
import tech.pegasys.signers.bls.keystore.KeyStoreLoader;
import tech.pegasys.signers.bls.keystore.model.KeyStoreData;
import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSConstants;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSSecretKey;
import tech.pegasys.teku.bls.impl.KeyPair;
import tech.pegasys.teku.bls.impl.SecretKey;
import tech.pegasys.web3signer.core.signing.ArtifactSignature;
import tech.pegasys.web3signer.core.signing.ArtifactSigner;
import tech.pegasys.web3signer.core.signing.BlsArtifactSignature;

import javax.net.ssl.KeyStoreBuilderParameters;
import java.nio.charset.StandardCharsets;

public class AwsSecretsManagerSigner implements ArtifactSigner {

  private BLSSecretKey blsSecretKey;

  public AwsSecretsManagerSigner(SecretsManagerClient secretsManagerClient, String secretName, String password){
    AwsSecretsManagerKey awsSecretsManagerKey = new AwsSecretsManagerKey(secretsManagerClient, secretName);

    KeyStoreData keyStoreData = KeyStoreLoader.loadFromString(awsSecretsManagerKey.getKeyStoreValue());
    Bytes privateKey = KeyStore.decrypt(password, keyStoreData);
    this.blsSecretKey = BLSSecretKey.fromBytes(Bytes32.wrap(privateKey));

    awsSecretsManagerKey.close();
  }

  @Override
  public String getIdentifier() {
    return this.blsSecretKey.toPublicKey().toString();
  }

  @Override
  public ArtifactSignature sign(Bytes message) {
    return new BlsArtifactSignature(BLS.sign(this.blsSecretKey, message));
  }
}
