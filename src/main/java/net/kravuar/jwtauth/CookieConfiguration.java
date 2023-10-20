package net.kravuar.jwtauth;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import net.kravuar.jwtauth.components.CookieUtils;
import net.kravuar.jwtauth.components.props.CookieProps;
import net.kravuar.jwtauth.components.props.JWTProps;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.util.WebUtils;

import java.util.function.Function;

@Configuration
@ConditionalOnExpression("#jwtProps.jwtStorageType = 'cookie'")
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
    public Function<HttpServletRequest, String> jwtExtractor() {
        return request -> WebUtils.getCookie(
                request,
                cookieProps.getAccessCookieName()
        ).getValue();
    }
}
