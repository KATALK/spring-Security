package security07;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;


/**
 * 启动类
 */
@EnableRedisHttpSession
@SpringBootApplication
public class Security07Application {

	public static void main(String[] args) {
		SpringApplication.run(Security07Application.class, args);
	}

}

