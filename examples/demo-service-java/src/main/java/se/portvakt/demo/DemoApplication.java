package se.portvakt.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * The Java demo service ("Tjänst C"): browser login, step-up, representation and its own API,
 * all through the Portvakt Spring Boot starter.
 */
@SpringBootApplication
@EnableConfigurationProperties(DemoProperties.class)
public class DemoApplication {
  public static void main(String[] args) {
    SpringApplication.run(DemoApplication.class, args);
  }
}
