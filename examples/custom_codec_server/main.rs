mod example_keyhouse;
use example_keyhouse::ExampleKeyhouse;

fn main() {
    keyhouse::server::entrypoint::<ExampleKeyhouse>();
}
