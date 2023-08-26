package security.securityFrame.Auth.config;

import javax.servlet.http.Cookie;

public enum AllowedOrigins {
    LOCALHOST_8080("http://localhost:8080"),
    LOCALHOST_8081("http://localhost:8081"),

    //refresh token 을 담은 쿠키의 오리진을 설정할 수 있습니다.
    COOKIE_ALLOW_ORIGIN("http://ac-ti-on.s3-website.ap-northeast-2.amazonaws.com");

    private final String origin;

    AllowedOrigins(String origin) {
        this.origin = origin;
    }

    public String getOrigin() {
        return origin;
    }
}


