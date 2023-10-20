package net.kravuar.jwtauth.components.props;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("jwt-auth.jwt.cookie")
@Setter
@Getter
public class CookieProps {
    private Boolean httpOnly = true;
    private String accessCookieName = "access";
    private String accessCookiePath = "/";
    private String refreshCookieName = "refresh";
    private String refreshCookiePath = "/auth/refresh";
}
