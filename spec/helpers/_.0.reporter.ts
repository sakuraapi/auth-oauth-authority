import SuiteInfo = jasmine.SuiteInfo;
import {
  DisplayProcessor,
  SpecReporter
} from 'jasmine-spec-reporter';
import 'source-map-support/register';

localReporter();

function localReporter() {
  class CustomProcessor extends DisplayProcessor {
    displayJasmineStarted(info: SuiteInfo, log: string): string {
      return `Jasmine ${log}`.blue;
    }
  }

  jasmine.getEnv().clearReporters();
  jasmine.getEnv().addReporter(new SpecReporter({
    customProcessors: [CustomProcessor],
    spec: {
      displayDuration: true,
      displayErrorMessages: true,
      displayFailed: true,
      displayPending: true,
      displayStacktrace: true,
      displaySuccessful: true
    },
    suite: {
      displayNumber: true
    },
    summary: {
      displayDuration: true,
      displayErrorMessages: true,
      displayFailed: true,
      displayPending: true,
      displayStacktrace: true,
      displaySuccessful: false
    }
  }));
}
