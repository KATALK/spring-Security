package security07.handler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * @Author EdiMen
 * @Data 2020/10/11--10:48
 * @Version 1.0
 */
@Component
public class RememberMeHandler implements PersistentTokenRepository {

    /**
     * token有效时间30天
     */
    private static final Long TOKEN_VALUE_DAYS = 15L;

    @Autowired
    private StringRedisTemplate stringRedisTemplate;
    @Override
    public void createNewToken(PersistentRememberMeToken persistentRememberMeToken) {
        String key = generateTokenKey(persistentRememberMeToken.getSeries());
        Map<String,String> map = new HashMap<>(8);
        map.put("username",persistentRememberMeToken.getUsername());
        map.put("tokenValue",persistentRememberMeToken.getTokenValue());
        map.put("date",String.valueOf(persistentRememberMeToken.getDate().getTime()));
        stringRedisTemplate.opsForHash().putAll(key,map);
        stringRedisTemplate.expire(key,TOKEN_VALUE_DAYS,TimeUnit.DAYS);
        saveUsernameAndSeries(persistentRememberMeToken.getUsername(),persistentRememberMeToken.getSeries());
    }

    @Override
    public void updateToken(String series, String tokenValue, Date lastUsed) {
        String key = generateTokenKey(series);
        Boolean hasSeries = stringRedisTemplate.hasKey(key);
        if (hasSeries==null || !hasSeries){
            return;
        }
        Map<String,String> map = new HashMap<>(4);
        map.put("tokenValue",tokenValue);
        map.put("date",String.valueOf(lastUsed.getTime()));
        stringRedisTemplate.opsForHash().putAll(key,map);
        stringRedisTemplate.expire(key,TOKEN_VALUE_DAYS,TimeUnit.DAYS);
        String username = stringRedisTemplate.opsForValue().get(generateUsernameAndSeriesKey(series));
        saveUsernameAndSeries(username,series);
    }

    @Override
    public PersistentRememberMeToken getTokenForSeries(String seriesId) {
        String key = generateTokenKey(seriesId);
        Map<Object, Object> entries = stringRedisTemplate.opsForHash().entries(key);
        if (entries==null){
            return null;
        }

        Object username = entries.get("username");
        Object tokenValue = entries.get("tokenValue");
        Object date = entries.get("date");
        if (null == username || null == tokenValue || null == date){
            return null;
        }
        Long timeStamp = Long.valueOf(String.valueOf(date));
        Date time = new Date(timeStamp);
        saveUsernameAndSeries(String.valueOf(username),seriesId);
        return new PersistentRememberMeToken(String.valueOf(username),seriesId,String.valueOf(tokenValue),time);
    }

    @Override
    public void removeUserTokens(String username) {
        String series = stringRedisTemplate.opsForValue().get(generateUsernameAndSeriesKey(username));
        if (series==null || series.trim().length()<=0){
            return;
        }
        stringRedisTemplate.delete(generateTokenKey(series));
        stringRedisTemplate.delete(generateUsernameAndSeriesKey(username));
        stringRedisTemplate.delete(generateUsernameAndSeriesKey(series));
    }

    /**
     * 相互保存，便于查询
     * @param username
     * @param series
     */
    private void saveUsernameAndSeries(String username,String series){
        stringRedisTemplate.opsForValue().set(generateUsernameAndSeriesKey(username),series,TOKEN_VALUE_DAYS*2, TimeUnit.DAYS);
        stringRedisTemplate.opsForValue().set(generateUsernameAndSeriesKey(series),username,TOKEN_VALUE_DAYS*2,TimeUnit.DAYS);
    }

    /**
     * 生成token key
     * @param series
     * @return
     */
    private String generateTokenKey(String series){
        return "spring:security:rememberMe:token:"+series;
    }
    /**
     * 生成 key
     * @param usernameOrSeries
     * @return
     */
    private String generateUsernameAndSeriesKey(String usernameOrSeries) {
        return "spring:security:rememberMe:"+usernameOrSeries;
    }


}
