package security35.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class HelloController {

    // 1. 可以get访问
    // http://localhost:8034/oauth/authorize?client_id=clientId&response_type=code&redirect_uri=http://localhost:8034/


    // 2. 必须post访问
    // http://localhost:8034/oauth/token?grant_type=authorization_code&code=授权码&redirect_uri=http://localhost:8034/&client_id=clientId&client_secret=secret




    /** 受保护的资源 */
    @GetMapping("/user")
    public Object info(Principal user){
        return user;
    }




    /** 不受保护的资源 */
    @GetMapping("/save/no")
    public String noSave(){
        return "no save";
    }
}

