package security.securityFrame.Auth.config;

import javax.servlet.http.Cookie;

public enum AllowedOrigins {
    LOCALHOST_3000("http://localhost:3000"),
    NETLIFY_APP("https://acti-on.netlify.app"),
    LOCALHOST_5173("http://localhost:5173"),
    EC2_AWS("http://ec2-52-78-205-102.ap-northeast-2.compute.amazonaws.com:8080"),
    S3_AWS("http://ac-ti-on.s3-website.ap-northeast-2.amazonaws.com"),

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


