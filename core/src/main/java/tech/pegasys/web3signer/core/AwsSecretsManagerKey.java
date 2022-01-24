package tech.pegasys.web3signer.core;

import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;
import software.amazon.awssdk.services.secretsmanager.model.DescribeSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.DescribeSecretResponse;
import software.amazon.awssdk.regions.Region;

import java.nio.charset.StandardCharsets;

public class AwsSecretsManagerKey {

  private SecretsManagerClient secretsManagerClient;
  private String secretName;
  private String publicKey;
  private byte[] privateKey;

  public static SecretsManagerClient createSecretsManagerClient(){

    Region region = Region.US_EAST_2;
    SecretsManagerClient secretsClient = SecretsManagerClient.builder()
      .region(region)
      .build();

    return secretsClient;

  }

  public static String requestPublicKey(SecretsManagerClient secretsManagerClient, String secretName){
    try {
      DescribeSecretRequest describeSecretRequest = DescribeSecretRequest.builder()
        .secretId(secretName)
        .build();

      DescribeSecretResponse response = secretsManagerClient.describeSecret(describeSecretRequest);
      String publicKey = response.name();
      return publicKey;
    }
    catch (SecretsManagerException e){
      System.err.println(e.awsErrorDetails().errorMessage());
      System.exit(1);
    }
    return null;
  }

  public static byte[] requestPrivateKey(SecretsManagerClient secretsManagerClient, String secretName){
    try {
      GetSecretValueRequest getSecretValueRequest = GetSecretValueRequest.builder()
        .secretId(secretName)
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

  public void close() { this.secretsManagerClient.close(); }

  public String getPublicKey() { return this.publicKey; }
  public byte[] getPrivateKey() { return this.privateKey; }

  public AwsSecretsManagerKey(String secretName){
    this.secretsManagerClient = createSecretsManagerClient();
    this.secretName = secretName;
    this.publicKey = requestPublicKey(this.secretsManagerClient, this.secretName);
    this.privateKey = requestPrivateKey(this.secretsManagerClient, this.secretName);
  }

}
