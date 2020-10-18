package security07.mapper;

import org.apache.ibatis.annotations.Mapper;
import security07.model.SysUser;

/**
 * @Author EdiMen
 * @Data 2020/10/10--22:33
 * @Version 1.0
 */
@Mapper
public interface SysUserMapper {
    SysUser selectByUserName(String username);
}
