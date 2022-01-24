package tech.pegasys.web3signer.core;

import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;
import software.amazon.awssdk.regions.Region;

import java.nio.charset.StandardCharsets;

public class AwsSecretsManagerKey {

  private SecretsManagerClient secretsManagerClient;
  private byte[] publicKey;
  private byte[] privateKey;

  public static SecretsManagerClient createSecretsManagerClient(){

    Region region = Region.US_EAST_1;
    SecretsManagerClient secretsClient = SecretsManagerClient.builder()
      .region(region)
      .build();

    return secretsClient;

  }

  public static byte[] requestPrivateKey(SecretsManagerClient secretsManagerClient, byte[] publicKey){
    try {
      GetSecretValueRequest getSecretValueRequest = GetSecretValueRequest.builder()
        .secretId(publicKey.toString())
        .build();

      GetSecretValueResponse valueResponse = secretsManagerClient.getSecretValue(getSecretValueRequest);
      byte[] privateKey = valueResponse.secretString().getBytes(StandardCharsets.UTF_8);

      return privateKey;
    }
    catch (SecretsManagerException e){
      System.err.println(e.awsErrorDetails().errorMessage());
      System.exit(1);
    }
    return null;
  }

  public byte[] getPublicKey() { return this.publicKey; }
  public byte[] getPrivateKey() { return this.privateKey; }

  public AwsSecretsManagerKey(byte[] publicKey){
    this.secretsManagerClient = createSecretsManagerClient();
    this.publicKey = publicKey;
    this.privateKey = requestPrivateKey(this.secretsManagerClient, this.publicKey);
  }

}
