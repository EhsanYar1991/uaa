package com.mciws.uaa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.ldap.embedded.EmbeddedLdapAutoConfiguration;
import org.springframework.context.annotation.Configuration;

@SpringBootApplication(exclude = {
        EmbeddedLdapAutoConfiguration.class
})
@Configuration
public class UAAApplication {

    public static void main(String[] args) {
        SpringApplication.run(UAAApplication.class, args);
    }


}
