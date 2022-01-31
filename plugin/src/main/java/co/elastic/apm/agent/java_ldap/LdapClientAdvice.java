/*
   Copyright 2021 Tobias Stadler

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package co.elastic.apm.agent.java_ldap;

import co.elastic.apm.api.ElasticApm;
import co.elastic.apm.api.Outcome;
import co.elastic.apm.api.Scope;
import co.elastic.apm.api.Span;
import com.sun.jndi.ldap.Connection;
import com.sun.jndi.ldap.LdapResult;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

public class LdapClientAdvice {

    @Advice.OnMethodEnter(suppress = Throwable.class, inline = false)
    public static Object onEnter(@Advice.Origin("#m") String methodName, @Advice.FieldValue(value = "conn", typing = Assigner.Typing.DYNAMIC) Connection connection) {
        Span span = ElasticApm.currentSpan()
                .startExitSpan("external", "ldap", null)
                .setName("LDAP " + methodName);

        if (connection != null) {
            span.setDestinationAddress(connection.host, connection.port);
            span.setDestinationService(connection.host + ":" + connection.port);
        }

        return span.activate();
    }

    @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class, inline = false)
    public static void onExit(@Advice.Enter Object scope, @Advice.Return LdapResult ldapResult, @Advice.Thrown Throwable t) {
        try {
            Span span = ElasticApm.currentSpan();
            if (t != null) {
                span.captureException(t);
                span.setOutcome(Outcome.FAILURE);
            } else {
                span.setOutcome((ldapResult != null && ldapResult.status == 0 /* LDAP_SUCCESS */) ? Outcome.SUCCESS : Outcome.FAILURE);
            }
            span.end();
        } finally {
            ((Scope) scope).close();
        }
    }
}
