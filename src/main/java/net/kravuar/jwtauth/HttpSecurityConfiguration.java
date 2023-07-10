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
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableConfigurationProperties(HttpProps.class)
public class HttpSecurityConfiguration {
    private final OrRequestMatcher unauthenticated;
    private final HttpProps httpProps;
    private final JWTProps jwtProps;

    public HttpSecurityConfiguration(HttpProps httpProps, JWTProps jwtProps) {
        this.httpProps = httpProps;
        this.jwtProps = jwtProps;
        this.unauthenticated = new OrRequestMatcher(
                httpProps.getUnauthenticatedServlets().stream()
                        .map(AntPathRequestMatcher::new)
                        .map(RequestMatcher.class::cast)
                        .toList()
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(httpProps.getCorsAllowed());
        configuration.setAllowCredentials(true);
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Access-Control-Allow-Origin"));
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    @ConditionalOnMissingBean
    public JWTAuthFilter jwtFilter(AuthenticationManager authenticationManager) {
        AuthenticationSuccessHandler emptySuccessHandler = (request, response, authentication) -> {};
        return new JWTAuthFilter(unauthenticated, jwtProps.getAccessCookieName(), authenticationManager, emptySuccessHandler);
    }

    @Bean
    @Scope("prototype")
    @Primary
    public HttpSecurity httpSecurity(HttpSecurity httpSecurity, JWTAuthFilter jwtFilter) throws Exception {
        return httpSecurity
                .cors(cors -> cors.configure(httpSecurity))
                .sessionManagement(configurer -> configurer
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .httpBasic(Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(unauthenticated).permitAll()
                )
                .addFilterAfter(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
