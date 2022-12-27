pipeline {
  agent any
  stages {
    stage('Prune Docker data') {
      steps {
        bat 'docker system prune -a --volumes -f'
      }
    }
    stage('Start container') {
      steps {
        bat 'docker compose up -d --no-color --wait'
        bat 'docker compose ps'
      }
    }
  }
//   post {
//     always {
//       bat 'docker compose down --remove-orphans -v'
//       bat 'docker compose ps'
//     }
//   }
}