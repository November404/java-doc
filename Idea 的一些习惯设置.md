### Idea 的一些习惯设置

###### 插件

1. CodeGlance

2. MyBatis Plugin 

3. Commit Template

4. JavaDoc

5. Maven Helper

6. Save Action

7. Find Bugs

8. Translation

###### 插件设置

- Java Doc 

  ```java
  /**\n
   * The type ${name}.\n
  <#if element.typeParameters?has_content>        * \n
  </#if><#list element.typeParameters as typeParameter>        * @param <${typeParameter.name}> the type parameter\n
  </#list> * @author November\n
   * @since ${.now?string["yyyy-MM-dd"]}
   */
  ```

- Save Action

  CTRL+SHIFT+S

  Optimize imports

  Reformat file

  Add missing @Override annotations

  Add blocks to if/while/for statements

###### 其他设置

  Compiler > Build project on automatically

  Debugger > HotSwap > Build project before reloading classes

  Editor > Code Style > Java > Class count to use import with * 50;Names count to use static import with * 30

  Editor > File Types > Ignored Files and Folders

  Editor > General > Auto Import > Add unambiguous imports on the fly;Optimize imports on the fly

  Dashboard

```xml
<component name="RunDashboard">
    <option name="configurationTypes">
      <set>
        <option value="SpringBootApplicationConfigurationType" />
      </set>
    </option>
    <option name="ruleStates">
      <list>
        <RuleState>
          <option name="name" value="ConfigurationTypeDashboardGroupingRule" />
        </RuleState>
        <RuleState>
          <option name="name" value="StatusDashboardGroupingRule" />
        </RuleState>
      </list>
    </option>
    <option name="contentProportion" value="0.2061776" />
  </component>
```

