package net.kravuar.jwtauth;

import lombok.RequiredArgsConstructor;
import net.kravuar.jwtauth.components.CookieUtils;
import net.kravuar.jwtauth.components.JWTExtractor;
import net.kravuar.jwtauth.components.props.CookieProps;
import net.kravuar.jwtauth.components.props.JWTProps;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.util.WebUtils;

@Configuration
@ConditionalOnProperty(value = "jwt-auth.jwt.jwt-storage-type", havingValue = "cookie", matchIfMissing = true)
@RequiredArgsConstructor
@EnableConfigurationProperties(CookieProps.class)
public class CookieConfiguration {
    private final CookieProps cookieProps;

    @Bean
    public CookieUtils cookieUtils(JWTProps jwtProps) {
        return new CookieUtils(cookieProps, jwtProps);
    }

    @Bean
    @ConditionalOnMissingBean
    public JWTExtractor jwtExtractor() {
        return request -> WebUtils.getCookie(
                request,
                cookieProps.getAccessCookieName()
        ).getValue();
    }
}
