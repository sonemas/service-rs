use svc::{
    application::{Application, ApplicationError},
    configuration::Configuration,
    telemetry,
};

#[actix_web::main]
async fn main() -> Result<(), ApplicationError> {
    //----------------------------------------------------------------------------------------
    // Configuration
    let configuration = Configuration::parse("SVC").expect("Failed to read configuration.");

    //----------------------------------------------------------------------------------------
    // Telemetry
    let subscriber = telemetry::create_subscriber("SERVICE", "info", std::io::stdout);
    telemetry::init(subscriber);

    //----------------------------------------------------------------------------------------
    // Application
    let application = Application::build(configuration)
        .await
        .expect("Couldn't build application");
    application.serve().await
}
