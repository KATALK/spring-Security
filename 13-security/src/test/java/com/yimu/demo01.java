package com.yimu;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import security13.Security13Application;

import java.util.Base64;

/**
 * @Author EdiMen
 * @Data 2020/10/18--10:13
 * @Version 1.0
 */
@SpringBootTest(classes = Security13Application.class)
@RunWith(SpringRunner.class)
public class demo01 {


    @Test
    public void test01(){

//        String encoding = encoding("哈哈");
//        System.out.println(encoding);
        String decoding = decoding("5ZOI5ZOI");
        System.out.println(decoding);

    }


    /**
     * 编码
     * @param input
     * @return
     */
    public static  String encoding(String input){
        return Base64.getUrlEncoder().encodeToString(input.getBytes());
    }

    /**
     * 解码
     * @param string
     * @return
     */
    public static  String decoding(String string){
        return new String(Base64.getDecoder().decode(string.getBytes()));
    }
}
