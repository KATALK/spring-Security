package security07.mapper;

import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface SysMenuMapper {

    List<String> selectRoleNamesByUrl(String url);
}


