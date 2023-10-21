package net.kravuar.jwtauth.components.props;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("jwt-auth.jwt.cookie")
@ConditionalOnProperty(value = "jwt-auth.jwt.jwt-storage-type", havingValue = "cookie", matchIfMissing = true)
@Setter
@Getter
public class CookieProps {
    private Boolean httpOnly = true;
    private String accessCookieName = "access";
    private String accessCookiePath = "/";
    private String refreshCookieName = "refresh";
    private String refreshCookiePath = "/auth/refresh";
}
