package net.kravuar.jwtauth;

import net.kravuar.jwtauth.components.HttpProps;
import net.kravuar.jwtauth.components.JWTAuthFilter;
import net.kravuar.jwtauth.components.JWTProps;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableConfigurationProperties(HttpProps.class)
public class HttpSecurityConfiguration {
    private final OrRequestMatcher unauthenticated;
    private final JWTProps jwtProps;

    public HttpSecurityConfiguration(HttpProps httpProps, JWTProps jwtProps) {
        this.jwtProps = jwtProps;
        this.unauthenticated = new OrRequestMatcher(
                httpProps.getUnauthenticatedEndpoints().stream()
                        .map(AntPathRequestMatcher::new)
                        .map(RequestMatcher.class::cast)
                        .toList()
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public JWTAuthFilter jwtFilter(AuthenticationManager authenticationManager) {
        return new JWTAuthFilter(unauthenticated, jwtProps.getAccessCookieName(), authenticationManager);
    }

    @Bean
    @Scope("prototype")
    @Primary
    public HttpSecurity httpSecurity(HttpSecurity httpSecurity, JWTAuthFilter jwtFilter) {
        return httpSecurity.addFilterAfter(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
