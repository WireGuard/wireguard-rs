use daemonize;
use std::io;

    error_chain! {
        foreign_links {
            Io(io::Error) #[doc = "Error during IO"];
            Daemonize(daemonize::DaemonizeError) #[doc = "Error during IO"];
        }

        errors {
//            Launch(phase: LaunchStage) {
//                description("An error occurred during startup")
//                display("Startup aborted: {:?} did not complete successfully", phase)
//            }
//
//            ConfigLoad(path: String) {
//                description("Config file not found")
//                display("Unable to read file `{}`", path)
//            }
        }
    }

//    impl From<LaunchStage> for ErrorKind {
//        fn from(v: LaunchStage) -> Self {
//            ErrorKind::Launch(v)
//        }
//    }
