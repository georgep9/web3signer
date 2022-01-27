package tech.pegasys.web3signer.core;

import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
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
  private String keyStoreValue;

  public static SecretsManagerClient createSecretsManagerClient(){

    Region region = Region.US_EAST_2;
    SecretsManagerClient secretsClient = SecretsManagerClient.builder()
      .region(region)
      .build();

    return secretsClient;

  }

  public static String requestSecretValue(SecretsManagerClient secretsManagerClient, String secretName){
    try {
      GetSecretValueRequest getSecretValueRequest = GetSecretValueRequest.builder()
        .secretId(secretName)
        .build();

      GetSecretValueResponse valueResponse = secretsManagerClient.getSecretValue(getSecretValueRequest);

      return valueResponse.secretString();
    }
    catch (SecretsManagerException e){
      System.err.println(e.awsErrorDetails().errorMessage());
      System.exit(1);
    }
    return null;
  }

  public static String extractKeyStoreValue(String secretValue){
    JsonObject secretValueJson = new JsonObject(secretValue);
    String keyStoreValue = secretValueJson.getString("keystore");
    return keyStoreValue;
  }

  public String getKeyStoreValue() { return this.keyStoreValue; }

  public void close() { this.secretsManagerClient.close(); }



  public AwsSecretsManagerKey(SecretsManagerClient secretsManagerClient, String secretName){
    this.secretsManagerClient = secretsManagerClient;
    this.secretName = secretName;
    this.keyStoreValue = extractKeyStoreValue(requestSecretValue(this.secretsManagerClient, this.secretName));
  }

}
