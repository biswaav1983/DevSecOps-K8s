pipeline {
    agent any
	environment {
		imageName = "quay.io/biswaav/numeric-app:${GIT_COMMIT}"
		deploymentName = "devsecops"
    		containerName = "devsecops-container"
    		serviceName = "devsecops-svc"
		applicationURL = "http://k8s-master-node"
    		applicationURI = "/increment/99"
           }

    tools {
        // Install the Maven version configured as "M3" and add it to the path.
        maven "maven_new"
    }

    stages {
        
	stage('Build') {
            steps {
                sh "mvn clean package -DskipTests=true"
                archive 'target/*.jar'
            }
        }
         
	stage('Unit Tests - JUnit and JaCoCo') {
            steps {
                sh "ls ; mvn test"
            }
        }

        stage('Mutation Tests - PIT') {
      	     steps {
        	 sh "mvn org.pitest:pitest-maven:mutationCoverage"
      	     }
    	}	

	 stage('SonarQube - SAST') {
     	   steps {
		 withSonarQubeEnv('SonarQube') {
        	  sh "mvn sonar:sonar -Dsonar.projectKey=numeric-application -Dsonar.host.url=http://k8s-master-node:9000"
      	          }
	timeout(time: 2, unit: 'MINUTES') {
	  script {
	    waitForQualityGate abortPipeline: true
        	}
	     }
   	        }	
        }

	stage('Vulnerability Scan - Docker ') {
      	   steps {
		parallel(
			"Dependency Scan": {
        	   	 sh "mvn dependency-check:check"
			},
			"Trivy Scan": {
           		  sh "bash trivy-docker-image-scan.sh"
          	           }
       		       )
      	 	   } 
      	      }

           stage('Docker Build and Push') {
            steps {
              withDockerRegistry([credentialsId: "docker-hub", url: "https://quay.io/"]) {
                sh 'printenv'
                sh 'sudo docker build -t quay.io/biswaav/numeric-app:""$GIT_COMMIT"" .'
                sh 'docker push quay.io/biswaav/numeric-app:""$GIT_COMMIT""'
            }
         }
      }

	   stage('Vulnerability Scan - Kubernetes') {
     	     steps {
		parallel(
	     "Kubesec Scan": {	
		sh "bash kubesec-scan.sh"
		},
	      "Trivy Scan": {
                sh "bash trivy-k8s-scan.sh"
                   }
             )	
      	  } 
        }	
           stage('K8S Deployment - DEV') {
               steps {  
                 withKubeConfig([credentialsId: 'kubeconfig']) {
                 sh "sed -i 's#replace#quay.io/biswaav/numeric-app:${GIT_COMMIT}#g' k8s_deployment_service.yaml"
                 sh "kubectl -n default apply -f k8s_deployment_service.yaml"
             }
          }
      }   
  	
	   stage('Integration Tests - DEV') {
      		steps {
        	script {
         	try {
            		withKubeConfig([credentialsId: 'kubeconfig']) {
              		sh "bash integration-test.sh"
            		}
                    } 
	    catch (e) {
            		withKubeConfig([credentialsId: 'kubeconfig']) {
              		sh "kubectl -n default rollout undo deploy ${deploymentName}"
                  }
            throw e
                     }
                  }    
               }
            }
	  

	   stage('OWASP ZAP - DAST') {
     		 steps {
       		 withKubeConfig([credentialsId: 'kubeconfig']) {
          	 sh 'bash zap.sh'
        }
      }
    }


}

	post {
    		always {
      			junit 'target/surefire-reports/*.xml'
      			jacoco execPattern: 'target/jacoco.exec'
      			pitmutation mutationStatsFile: '**/target/pit-reports/**/mutations.xml'
      			dependencyCheckPublisher pattern: 'target/dependency-check-report.xml'
publishHTML([allowMissing: false, alwaysLinkToLastBuild: true, keepAll: true, reportDir: 'owasp-zap-report', reportFiles: 'zap_report.html', reportName: 'OWASP ZAP HTML Report', reportTitles: 'OWASP ZAP HTML Report'])
   		 }

    // success {

    // }

    // failure {

    // }

	}
   }
