/*
 * The MIT License
 *
 * Copyright (c) 2021, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package io.jenkins.plugins.safebatch;

import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import hudson.Functions;
import hudson.model.Build;
import hudson.model.Cause;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.ParametersAction;
import hudson.model.ParametersDefinitionProperty;
import hudson.model.Result;
import hudson.model.StringParameterDefinition;
import hudson.model.StringParameterValue;
import hudson.tasks.BatchFile;
import io.jenkins.plugins.environment_filter_utils.matchers.run.ExactJobFullNameRunMatcher;
import jenkins.tasks.filters.EnvVarsFilterGlobalConfiguration;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class BatchSanitizerGlobalRuleTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void globalRule_canBe_ignoreForGivenJobs() throws Exception {
        assumeTrue(Functions.isWindows());

        EnvVarsFilterGlobalConfiguration.getAllActivatedGlobalRules().clear();
        BatchSanitizerGlobalRule globalRule = new BatchSanitizerGlobalRule();
        globalRule.setMode(BatchSanitizerGlobalRule.EnvironmentSanitizerStandardMode.REPLACE);
        EnvVarsFilterGlobalConfiguration.getAllActivatedGlobalRules().add(globalRule);

        FreeStyleProject p = j.createFreeStyleProject("job for test");
        BatchFile batch = new BatchFile("echo \"begin %what% %who% end\"");
        p.getBuildersList().add(batch);
        p.addProperty(new ParametersDefinitionProperty(
                new StringParameterDefinition("what", "Hello"), new StringParameterDefinition("who", "World")));

        { // with dangerous characters => remove them
            FreeStyleBuild build = j.assertBuildStatus(
                    Result.SUCCESS,
                    p.scheduleBuild2(
                            0,
                            (Cause) null,
                            new ParametersAction(
                                    new StringParameterValue("what", "hello"),
                                    new StringParameterValue("who", "begin\" & dir \"../../\" & echo \"end"))));

            assertContainsSequentially(build, "begin hello REDACTED end");
        }
        { // with dangerous characters but job is excluded
            ExactJobFullNameRunMatcher matcher = new ExactJobFullNameRunMatcher();
            matcher.setName("job for test");
            globalRule.getJobExclusionList().add(matcher);

            FreeStyleBuild build = j.assertBuildStatus(
                    Result.SUCCESS,
                    p.scheduleBuild2(
                            0,
                            (Cause) null,
                            new ParametersAction(
                                    new StringParameterValue("what", "hello"),
                                    new StringParameterValue("who", "100%"))));

            assertContainsSequentially(build, "begin hello 100% end");
        }
    }

    private void assertContainsSequentially(Build<?, ?> build, String... values) throws Exception {
        int i = 0;
        for (String line : build.getLog(128)) {
            if (line.contains(values[i])) {
                i++;
                if (i >= values.length) {
                    return;
                }
            }
        }
        fail("Does not contains the value: " + values[i]);
    }
}
