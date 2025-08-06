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

import hudson.EnvVars;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.Launcher;
import hudson.model.Descriptor;
import hudson.model.Run;
import hudson.tasks.BatchFile;
import io.jenkins.plugins.environment_filter_utils.matchers.run.RunMatcher;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import jenkins.model.Jenkins;
import jenkins.tasks.filters.EnvVarsFilterException;
import jenkins.tasks.filters.EnvVarsFilterGlobalRule;
import jenkins.tasks.filters.EnvVarsFilterRuleContext;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.jvnet.localizer.Localizable;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * Global rule to filter freestyle Windows Batch step and also pipeline's one
 * It will be triggered on dangerous characters present in variable's value.
 * The action depends on the {@link EnvironmentSanitizerStandardMode} configured.
 */
public class BatchSanitizerGlobalRule implements EnvVarsFilterGlobalRule {
    private static final Logger LOGGER = Logger.getLogger(BatchSanitizerGlobalRule.class.getName());

    // Ideally we would figure out a better way to filter safe/unsafe env vars in batch than just presence of specific
    // characters
    // Unfortunately, https://ss64.com/nt/syntax-esc.html#escape seems too complex without knowing the script
    private static String DANGEROUS_CHARACTERS =
            System.getProperty(BatchSanitizerGlobalRule.class.getName() + ".DANGEROUS_CHARACTERS", "|^&%\"<>");

    private EnvironmentSanitizerStandardMode mode = EnvironmentSanitizerStandardMode.FAIL;

    private List<RunMatcher> jobExclusionList = new ArrayList<>();

    @DataBoundConstructor
    public BatchSanitizerGlobalRule() {
        super();
    }

    @DataBoundSetter
    public void setMode(@Nonnull EnvironmentSanitizerStandardMode mode) {
        this.mode = mode;
    }

    // used by Jelly view
    public @Nonnull EnvironmentSanitizerStandardMode getMode() {
        return mode;
    }

    @DataBoundSetter
    public void setJobExclusionList(List<RunMatcher> jobExclusionList) {
        this.jobExclusionList = jobExclusionList;
    }

    // used by Jelly view
    public List<RunMatcher> getJobExclusionList() {
        return jobExclusionList;
    }

    @Override
    public boolean isApplicable(@CheckForNull Run<?, ?> run, @Nonnull Object builder, @Nonnull Launcher launcher) {
        if (run != null) {
            boolean isExcluded = jobExclusionList.stream().anyMatch(jobExclusion -> jobExclusion.test(run));
            if (isExcluded) {
                LOGGER.log(
                        Level.CONFIG,
                        "Not applicable because the job {0} is excluded.",
                        run.getParent().getFullName());
                return false;
            }
        }

        return builder instanceof BatchFile
                ||
                // to support workflow-durable-task-step without requiring a dependency
                // builder.getClass().getName().equals("org.jenkinsci.plugins.durabletask.WindowsBatchScript");
                builder.getClass()
                        .getName()
                        .equals("org.jenkinsci.plugins.workflow.steps.durable_task.BatchScriptStep");
    }

    @Override
    public void filter(@Nonnull EnvVars envVars, @Nonnull EnvVarsFilterRuleContext context)
            throws EnvVarsFilterException {
        String dangerousCharactersString = DANGEROUS_CHARACTERS;
        if (StringUtils.isBlank(dangerousCharactersString)) {
            return;
        }

        String[] dangerousCharactersArray = dangerousCharactersString.split("");
        analyzeVariables(dangerousCharactersArray, envVars, mode, context);
    }

    private void analyzeVariables(
            String[] dangerousCharacters,
            EnvVars envVars,
            EnvironmentSanitizerStandardMode mode,
            @Nonnull EnvVarsFilterRuleContext context)
            throws EnvVarsFilterException {
        // this code is executed on the agent, retrieving agent's system env. variables
        Map<String, String> systemEnvVars = EnvVars.masterEnvVars;

        for (Map.Entry<String, String> e : envVars.entrySet()) {
            String variableName = e.getKey();
            String variableValue = e.getValue();

            // systemEnvVars's keys are case insensitive
            String systemValue = systemEnvVars.get(variableName);
            if (systemValue == null || !systemValue.equals(variableValue)) {
                analyzeSingleVariable(dangerousCharacters, envVars, mode, context, variableName, variableValue);
            }
            // otherwise we have a system variable that is not modified, we ignore it
        }
    }

    private void analyzeSingleVariable(
            String[] dangerousCharacters,
            EnvVars envVars,
            EnvironmentSanitizerStandardMode mode,
            @Nonnull EnvVarsFilterRuleContext context,
            String variableName,
            String variableValue)
            throws EnvVarsFilterException {
        boolean done = false;
        for (int i = 0; i < dangerousCharacters.length && !done; i++) {
            String dangerousCharacter = dangerousCharacters[i];
            if (variableValue.contains(dangerousCharacter)) {
                done = mode.actOnDangerousVariable(
                        this, envVars, variableName, variableValue, dangerousCharacter, context);
            }
        }
    }

    // the ordinal is used to sort the rules in term of execution, the smaller value first
    // and take care of the fact that local rules are always applied before global ones
    @Extension(ordinal = DescriptorImpl.ORDER)
    @Symbol("batchSanitizer")
    public static final class DescriptorImpl extends Descriptor<EnvVarsFilterGlobalRule> {
        public static final int ORDER = 1000;

        public DescriptorImpl() {
            super();
            load();
        }

        @Override
        public @Nonnull String getDisplayName() {
            return Messages.BatchSanitizerGlobalRule_DisplayName();
        }

        // used by Jelly
        public static ExtensionList<Descriptor<RunMatcher>> getAllJobExclusions() {
            return Jenkins.get().getDescriptorList(RunMatcher.class);
        }
    }

    public enum EnvironmentSanitizerStandardMode {
        /**
         * Force the job to fail
         */
        FAIL(Messages._DangerousCharacterMode_FAIL()) {
            @Override
            public boolean actOnDangerousVariable(
                    BatchSanitizerGlobalRule rule,
                    EnvVars envVars,
                    String variableName,
                    String variableValue,
                    String dangerousCharacter,
                    EnvVarsFilterRuleContext context)
                    throws EnvVarsFilterException {
                jobAndSystemLog(
                        String.format(
                                "%s: Unsafe environment variable %s: Metacharacter [%s] present, failing this build step",
                                rule.getDescriptor().getDisplayName(), variableName, dangerousCharacter),
                        context,
                        Level.FINE);
                throw new EnvVarsFilterException("Failing the build step")
                        .withVariable(variableName) // TODO i18n
                        .withRule(rule);
            }
        },
        /**
         * Replace the dangerous variables by REDACTED
         */
        REPLACE(Messages._DangerousCharacterMode_REPLACE()) {
            @Override
            public boolean actOnDangerousVariable(
                    BatchSanitizerGlobalRule rule,
                    EnvVars envVars,
                    String variableName,
                    String variableValue,
                    String dangerousCharacter,
                    EnvVarsFilterRuleContext context) {
                envVars.put(variableName, "REDACTED");

                jobAndSystemLog(
                        String.format(
                                "%s: Unsafe environment variable %s: Metacharacter [%s] present, replaced value with: REDACTED",
                                rule.getDescriptor().getDisplayName(), variableName, dangerousCharacter),
                        context,
                        Level.FINE);

                return true;
            }
        },
        /**
         * Just log the character and the name of the field
         * (to avoid disclosing passwords / credentials)
         */
        WARN(Messages._DangerousCharacterMode_WARN()) {
            @Override
            public boolean actOnDangerousVariable(
                    BatchSanitizerGlobalRule rule,
                    EnvVars envVars,
                    String variableName,
                    String variableValue,
                    String dangerousCharacter,
                    EnvVarsFilterRuleContext context) {
                jobAndSystemLog(
                        String.format(
                                "%s: Unsafe environment variable %s: Metacharacter [%s] present",
                                rule.getDescriptor().getDisplayName(), variableName, dangerousCharacter),
                        context,
                        Level.WARNING);

                return false;
            }
        };

        public final Localizable label;

        EnvironmentSanitizerStandardMode(Localizable label) {
            this.label = label;
        }

        public static EnvironmentSanitizerStandardMode getDefault() {
            return FAIL;
        }

        /**
         * @return true if there is no need to go further with the dangerous characters
         */
        public abstract boolean actOnDangerousVariable(
                BatchSanitizerGlobalRule rule,
                EnvVars envVars,
                String variableName,
                String variableValue,
                String dangerousCharacter,
                EnvVarsFilterRuleContext context)
                throws EnvVarsFilterException;

        private static void jobAndSystemLog(
                @Nonnull String message, @Nonnull EnvVarsFilterRuleContext context, @Nonnull Level level) {
            context.getTaskListener().getLogger().println(message);
            LOGGER.log(level, message);
        }
    }
}
