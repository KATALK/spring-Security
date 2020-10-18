package security29.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import security29.service.MyBatisClientDetailsService;

import java.util.Map;

@RestController
public class ClientsController {

    @Autowired
    public MyBatisClientDetailsService myBatisClientDetailsService;

    @PostMapping("oauth/client/insert")
    public Object insert(@RequestBody Map map){
        return myBatisClientDetailsService.insert(map);
    }

}

