package net.kravuar.jwtauth.components.props;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties("jwt-auth.http")
@Setter
@Getter
public class
HttpProps {
    private List<String> unauthenticatedPathMatchers = new ArrayList<>(List.of(
            "/auth/**",
            "/error/**"
    ));
    private List<String> authenticatedPathMatchers = new ArrayList<>(List.of("/auth/refresh"));
}