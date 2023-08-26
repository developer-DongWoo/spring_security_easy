package security.securityFrame;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@EnableJpaAuditing
@SpringBootApplication
public class SecurityFrameApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityFrameApplication.class, args);
	}

}
