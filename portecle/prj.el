;; Configuration for JDEE (Java Development Environment for Emacs)
(jde-set-project-name "portecle")
(jde-set-variables
 '(jde-db-source-directories (quote ("./src/main")))
 '(jde-global-classpath (quote ("./build/classes" "./lib/bcprov.jar")))
 '(jde-run-application-class "net.sf.portecle.FPortecle")
 '(c-file-style "stroustrup")
 ;'(c-file-offsets (quote (inline-open . 0)))
)
