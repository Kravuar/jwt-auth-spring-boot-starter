package net.kravuar.jwtauth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

@AutoConfiguration(before = WebMvcAutoConfiguration.class)
@ConditionalOnProperty(value = "jwt-auth.enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnClass({HttpSecurity.class, HttpServletRequest.class})
@ConfigurationPropertiesScan(basePackages = "net.kravuar.jwtauth.components.props")
@Import({JWTConfiguration.class, AuthenticationManagerConfiguration.class, CookieConfiguration.class, HttpSecurityConfiguration.class})
public class JWTAuthAutoConfiguration {

}
