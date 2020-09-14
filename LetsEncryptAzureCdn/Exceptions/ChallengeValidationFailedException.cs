using System;

namespace LetsEncryptAzureCdn.Exceptions
{

    [Serializable]
    public class ChallengeValidationFailedException : Exception
    {
        public ChallengeValidationFailedException() { }
        public ChallengeValidationFailedException(string message) : base(message) { }
        public ChallengeValidationFailedException(string message, Exception inner) : base(message, inner) { }
        protected ChallengeValidationFailedException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}
